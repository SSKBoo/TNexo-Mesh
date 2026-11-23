//! Relay tipo DERP: cuando el UDP directo falla, los frames NM1 cifrados se
//! reenvían por el WebSocket de señalización del backend (TLS/WSS en producción).
//! El backend solo ve bytes cifrados en base64.

use crate::nat;
use crate::session;
use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Región de relay DERP distribuida con latencia medida para selección automática.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpRegion {
    pub id: u16,
    pub name: String,
    pub endpoint: String,
    pub rtt_ms: u32,
}

/// Selecciona la región DERP con menor RTT (excluyendo nodos caídos con `rtt_ms == u32::MAX`).
pub fn select_nearest_derp_region(regions: &[DerpRegion]) -> Option<&DerpRegion> {
    regions
        .iter()
        .filter(|r| r.rtt_ms < u32::MAX && !r.endpoint.is_empty())
        .min_by_key(|r| r.rtt_ms)
}

/// Construye frame DERP dirigido sin broadcast: `NM2 | dst_pubkey(32B) | nm1_frame`.
pub fn build_nm2_routed_frame(dst_pubkey: &[u8; 32], nm1_frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 32 + nm1_frame.len());
    out.extend_from_slice(b"NM2");
    out.extend_from_slice(dst_pubkey);
    out.extend_from_slice(nm1_frame);
    out
}

#[derive(Debug)]
pub enum NodeEvent {
    Hello { vip: String, name: String, from: SocketAddr },
    Ack { vip: String, from: SocketAddr },
    DiscoPing { vip: String, tx_id: u64, from: SocketAddr },
    DiscoPong { vip: String, tx_id: u64, from: SocketAddr },
    Packet { sender_vip: String, packet: Vec<u8> },
}

/// Cliente userspace del túnel: intenta UDP directo, sondeo Disco y cae al relay DERP.
pub struct Node {
    pub local_vip: String,
    pub peer_vip: String,
    sock: UdpSocket,
    peer_addr: Option<SocketAddr>,
    relay_tx: Option<Sender<Vec<u8>>>,
    direct_ok: Arc<Mutex<bool>>,
    last_direct_rx: Arc<Mutex<Option<Instant>>>,
    pending_disco: Mutex<Option<(u64, Instant)>>,
    disco_rtt_ms: Arc<Mutex<Option<u32>>>,
}

impl Node {
    pub fn bind(local_vip: &str, peer_vip: &str, port: u16) -> Result<Self> {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        Ok(Self {
            local_vip: local_vip.to_string(),
            peer_vip: peer_vip.to_string(),
            sock,
            peer_addr: None,
            relay_tx: None,
            direct_ok: Arc::new(Mutex::new(false)),
            last_direct_rx: Arc::new(Mutex::new(None)),
            pending_disco: Mutex::new(None),
            disco_rtt_ms: Arc::new(Mutex::new(None)),
        })
    }

    pub fn local_port(&self) -> Result<u16> {
        Ok(self.sock.local_addr()?.port())
    }

    pub fn set_peer(&mut self, addr: SocketAddr) {
        self.peer_addr = Some(addr);
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Activa el canal de relay. Devuelve un receiver de frames salientes para
    /// que el transporte WSS los envíe al backend como mensaje `relay`.
    pub fn enable_relay(&mut self) -> Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        self.relay_tx = Some(tx);
        rx
    }

    /// Construye el frame cifrado compatible con Android:
    /// `NM1 | len(senderVip) | senderVip | ciphertext(AEAD)`
    pub fn build_nm1_frame(&self, ip_packet: &[u8]) -> Result<Vec<u8>> {
        let frame_plain = session::seal(&self.peer_vip, ip_packet)?;
        let sender = self.local_vip.as_bytes();
        let mut frame = Vec::with_capacity(4 + sender.len() + frame_plain.len());
        frame.extend_from_slice(b"NM1");
        frame.push(sender.len() as u8);
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&frame_plain);
        Ok(frame)
    }

    /// Parsea y descifra un frame `NM1` devolviendo `(sender_vip, plaintext)`.
    pub fn parse_nm1_frame(frame: &[u8]) -> Result<(String, Vec<u8>)> {
        if frame.len() < 6 || &frame[0..3] != b"NM1" {
            return Err(anyhow!("frame NM1 inválido"));
        }
        let sender_len = frame[3] as usize;
        if sender_len == 0 || frame.len() <= 4 + sender_len {
            return Err(anyhow!("frame NM1 truncado"));
        }
        let sender_vip = std::str::from_utf8(&frame[4..4 + sender_len])?.to_string();
        let packet = session::open(&sender_vip, &frame[4 + sender_len..])?;
        Ok((sender_vip, packet))
    }

    pub fn feed_relay_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let (_vip, packet) = Self::parse_nm1_frame(frame)?;
        Ok(packet)
    }

    /// Envía `NM_HELLO` UDP directo al par configurado para iniciar hole-punching.
    pub fn send_hello(&self, node_name: &str) -> Result<()> {
        if let Some(addr) = self.peer_addr {
            let port = self.sock.local_addr()?.port();
            let msg = format!("NM_HELLO|{}|{node_name}|0.0.0.0:{port}", self.local_vip);
            self.sock.send_to(msg.as_bytes(), addr)?;
        }
        Ok(())
    }

    /// Envía una sonda Disco `NM_DISCO_PING|<tx_id>|<local_vip>` para promoción en caliente DERP -> P2P.
    pub fn send_disco_ping(&self, tx_id: u64) -> Result<()> {
        if let Some(addr) = self.peer_addr {
            *self.pending_disco.lock().unwrap() = Some((tx_id, Instant::now()));
            let msg = format!("NM_DISCO_PING|{tx_id}|{}", self.local_vip);
            self.sock.send_to(msg.as_bytes(), addr)?;
        }
        Ok(())
    }

    /// Evasión de NAT simétrico (Birthday Paradox): dispara sondas Disco desde 32 sockets efímeros.
    pub fn probe_symmetric_nat(
        &self,
        peer_ip: Ipv4Addr,
        base_port: u16,
        port_spread: u16,
        tx_id: u64,
    ) -> usize {
        let sockets = nat::bind_birthday_sockets(32);
        let msg = format!("NM_DISCO_PING|{tx_id}|{}", self.local_vip);
        nat::spray_birthday_probes(&sockets, peer_ip, base_port, port_spread, msg.as_bytes())
    }

    /// Si el camino UDP directo dejó de responder durante `stale_after`, degrada a DERP sin cortar flujo.
    pub fn fallback_to_relay_if_stale(&self, stale_after: Duration) -> bool {
        let mut direct = self.direct_ok.lock().unwrap();
        if !*direct {
            return false;
        }
        let stale = match *self.last_direct_rx.lock().unwrap() {
            Some(ts) => ts.elapsed() > stale_after,
            None => true,
        };
        if stale {
            *direct = false;
            return true;
        }
        false
    }

    pub fn last_disco_rtt_ms(&self) -> Option<u32> {
        *self.disco_rtt_ms.lock().unwrap()
    }

    /// Lee un datagrama UDP (con timeout de 50ms) y procesa `NM_HELLO`, `NM_ACK`, `NM_DISCO_*` o `NM1`.
    pub fn poll_udp_once(&mut self) -> Result<Option<NodeEvent>> {
        let mut buf = [0u8; 4200];
        let (len, from) = match self.sock.recv_from(&mut buf) {
            Ok(res) => res,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        let pkt = &buf[..len];
        if pkt.starts_with(b"NM_HELLO|") {
            let text = String::from_utf8_lossy(pkt);
            let mut parts = text.split('|');
            let _ = parts.next();
            let vip = parts.next().unwrap_or("").trim().to_string();
            let name = parts.next().unwrap_or("peer").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                self.peer_addr = Some(from);
                *self.direct_ok.lock().unwrap() = true;
                *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                let ack = format!("NM_ACK|{}|rust-cli|direct", self.local_vip);
                let _ = self.sock.send_to(ack.as_bytes(), from);
                return Ok(Some(NodeEvent::Hello { vip, name, from }));
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_ACK|") {
            let text = String::from_utf8_lossy(pkt);
            let mut parts = text.split('|');
            let _ = parts.next();
            let vip = parts.next().unwrap_or("").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                self.peer_addr = Some(from);
                *self.direct_ok.lock().unwrap() = true;
                *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                return Ok(Some(NodeEvent::Ack { vip, from }));
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_DISCO_PING|") {
            let text = String::from_utf8_lossy(pkt);
            let mut parts = text.split('|');
            let _ = parts.next();
            let tx_id = parts.next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            let vip = parts.next().unwrap_or("").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                self.peer_addr = Some(from);
                *self.direct_ok.lock().unwrap() = true;
                *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                let pong = format!("NM_DISCO_PONG|{tx_id}|{}", self.local_vip);
                let _ = self.sock.send_to(pong.as_bytes(), from);
                return Ok(Some(NodeEvent::DiscoPing { vip, tx_id, from }));
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_DISCO_PONG|") {
            let text = String::from_utf8_lossy(pkt);
            let mut parts = text.split('|');
            let _ = parts.next();
            let tx_id = parts.next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            let vip = parts.next().unwrap_or("").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                self.peer_addr = Some(from);
                *self.direct_ok.lock().unwrap() = true;
                *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                if let Some((pending_id, started)) = *self.pending_disco.lock().unwrap() {
                    if pending_id == tx_id {
                        *self.disco_rtt_ms.lock().unwrap() =
                            Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32);
                    }
                }
                return Ok(Some(NodeEvent::DiscoPong { vip, tx_id, from }));
            }
            return Ok(None);
        }

        if pkt.len() >= 6 && &pkt[0..3] == b"NM1" {
            if let Ok((sender_vip, packet)) = Self::parse_nm1_frame(pkt) {
                self.peer_addr = Some(from);
                *self.direct_ok.lock().unwrap() = true;
                *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                return Ok(Some(NodeEvent::Packet { sender_vip, packet }));
            }
        }

        Ok(None)
    }

    /// Envía un paquete IP: cifra con la sesión del par y prueba UDP directo
    /// (si el enlace directo está confirmado o configurado); si no, usa el relay.
    pub fn send_packet(&self, ip_packet: &[u8]) -> Result<()> {
        let frame = self.build_nm1_frame(ip_packet)?;

        if *self.direct_ok.lock().unwrap() {
            if let Some(addr) = self.peer_addr {
                if self.sock.send_to(&frame, addr).is_ok() {
                    return Ok(());
                }
            }
        } else if self.relay_tx.is_none() {
            // Compatibilidad: si no hay relay activado pero sí peer_addr, intentar UDP directo.
            if let Some(addr) = self.peer_addr {
                if self.sock.send_to(&frame, addr).is_ok() {
                    *self.direct_ok.lock().unwrap() = true;
                    return Ok(());
                }
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

fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Construye un paquete IPv4 ICMP Echo Request válido (para pruebas userspace).
pub fn build_icmp_echo_request(src_vip: &str, dst_vip: &str, seq: u16) -> Result<Vec<u8>> {
    let src: Ipv4Addr = src_vip.parse()?;
    let dst: Ipv4Addr = dst_vip.parse()?;
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[2..4].copy_from_slice(&(28u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&seq.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_csum = inet_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMP Echo Request (type=8, code=0)
    pkt[20] = 8;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&0x4E4Du16.to_be_bytes()); // id "NM"
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    let icmp_csum = inet_checksum(&pkt[20..28]);
    pkt[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
    Ok(pkt)
}

/// Si `req` es un ICMP Echo Request IPv4 destinado a `local_vip`, construye el Echo Reply.
pub fn try_build_icmp_echo_reply(req: &[u8], local_vip: &str) -> Option<Vec<u8>> {
    if req.len() < 28 || (req[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((req[0] & 0x0F) as usize) * 4;
    if ihl < 20 || req.len() < ihl + 8 || req[9] != 1 {
        return None;
    }
    if req[ihl] != 8 || req[ihl + 1] != 0 {
        return None;
    }
    let dst = Ipv4Addr::new(req[16], req[17], req[18], req[19]);
    let expected: Ipv4Addr = local_vip.parse().ok()?;
    if dst != expected {
        return None;
    }

    let mut reply = req.to_vec();
    // Intercambiar src <-> dst IP
    reply[12..16].copy_from_slice(&req[16..20]);
    reply[16..20].copy_from_slice(&req[12..16]);
    reply[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = inet_checksum(&reply[0..ihl]);
    reply[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMP Echo Reply (type=0)
    reply[ihl] = 0;
    reply[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let icmp_csum = inet_checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(reply)
}
