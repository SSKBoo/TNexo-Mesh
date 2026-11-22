//! Relay tipo DERP: cuando el UDP directo falla, los frames NM1 cifrados se
//! reenvían por el WebSocket de señalización del backend (TLS/WSS en producción).
//! El backend solo ve bytes cifrados en base64.

use crate::session;
use anyhow::{anyhow, Result};
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Cliente userspace del túnel: intenta UDP directo y cae al relay.
pub struct Node {
    pub local_vip: String,
    pub peer_vip: String,
    sock: UdpSocket,
    peer_addr: Option<std::net::SocketAddr>,
    relay_tx: Option<Sender<Vec<u8>>>,
    direct_ok: Arc<Mutex<bool>>,
}

impl Node {
    pub fn bind(local_vip: &str, peer_vip: &str, port: u16) -> Result<Self> {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        sock.set_read_timeout(Some(Duration::from_millis(300)))?;
        Ok(Self {
            local_vip: local_vip.to_string(),
            peer_vip: peer_vip.to_string(),
            sock,
            peer_addr: None,
            relay_tx: None,
            direct_ok: Arc::new(Mutex::new(false)),
        })
    }

    pub fn set_peer(&mut self, addr: std::net::SocketAddr) {
        self.peer_addr = Some(addr);
    }

    /// Activa el canal de relay. Devuelve un receiver de frames salientes para
    /// que el transporte WSS los envíe al backend como mensaje `relay`.
    pub fn enable_relay(&mut self) -> Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        self.relay_tx = Some(tx);
        rx
    }

    pub fn feed_relay_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        // Frame recibido por WSS: NM1 | len | vip | ciphertext ->_descifrar
        if frame.len() < 6 || frame[0] != b'N' || frame[1] != b'M' || frame[2] != b'1' {
            return Err(anyhow!("frame NM1 inválido"));
        }
        let sender_len = frame[3] as usize;
        if frame.len() < 4 + sender_len {
            return Err(anyhow!("frame NM1 truncado"));
        }
        let sender_vip = std::str::from_utf8(&frame[4..4 + sender_len])?;
        let packet = session::open(sender_vip, &frame[4 + sender_len..])?;
        Ok(packet)
    }

    /// Envía un paquete IP: cifra con la sesión del par y prueba UDP directo;
    /// si falla, lo publica en el canal relay.
    pub fn send_packet(&self, ip_packet: &[u8]) -> Result<()> {
        let frame_plain = session::seal(&self.peer_vip, ip_packet)?;
        let sender = self.local_vip.as_bytes();
        let mut frame = Vec::with_capacity(4 + sender.len() + frame_plain.len());
        frame.extend_from_slice(b"NM1");
        frame.push(sender.len() as u8);
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&frame_plain);

        if let Some(addr) = self.peer_addr {
            if self.sock.send_to(&frame, addr).is_ok() {
                *self.direct_ok.lock().unwrap() = true;
                return Ok(());
            }
        }
        if let Some(tx) = &self.relay_tx {
            tx.send(frame)?;
            return Ok(());
        }
        Err(anyhow!("sin UDP directo ni relay disponible"))
    }

    pub fn using_direct(&self) -> bool {
        *self.direct_ok.lock().unwrap()
    }
}
