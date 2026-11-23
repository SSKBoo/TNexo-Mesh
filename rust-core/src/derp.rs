//! Relay tipo DERP (NM2 dirigido) + máquina de estados Magicsock/Disco y rekeying PFS automático.

use crate::nat;
use crate::session;
use crate::ws_client::{base64_decode, base64_encode};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
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

fn parse_endpoint_host_port(endpoint: &str) -> Option<(String, u16)> {
    let stripped = endpoint
        .trim()
        .strip_prefix("wss://")
        .map(|s| (true, s))
        .or_else(|| endpoint.trim().strip_prefix("ws://").map(|s| (false, s)))
        .or_else(|| endpoint.trim().strip_prefix("https://").map(|s| (true, s)))
        .or_else(|| endpoint.trim().strip_prefix("http://").map(|s| (false, s)))
        .unwrap_or((false, endpoint.trim()));
    let host_port = stripped.1.split('/').next()?;
    if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p.parse::<u16>().ok()?;
        Some((h.to_string(), port))
    } else {
        Some((host_port.to_string(), if stripped.0 { 443 } else { 80 }))
    }
}

/// Mide latencia TCP real hacia cada región DERP para elegir el Home DERP más cercano.
pub fn probe_derp_regions(regions: &mut [DerpRegion]) {
    let timeout = Duration::from_millis(600);
    for region in regions.iter_mut() {
        let Some((host, port)) = parse_endpoint_host_port(&region.endpoint) else {
            region.rtt_ms = u32::MAX;
            continue;
        };
        let Ok(mut addrs) = format!("{host}:{port}").to_socket_addrs() else {
            region.rtt_ms = u32::MAX;
            continue;
        };
        let Some(addr) = addrs.next() else {
            region.rtt_ms = u32::MAX;
            continue;
        };
        let started = Instant::now();
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            region.rtt_ms = started.elapsed().as_millis().min(u32::MAX as u128 - 1) as u32;
        } else {
            region.rtt_ms = u32::MAX;
        }
    }
}

/// Selecciona la región DERP con menor RTT (excluyendo nodos caídos con `rtt_ms == u32::MAX`).
pub fn select_nearest_derp_region(regions: &[DerpRegion]) -> Option<&DerpRegion> {
    regions
        .iter()
        .filter(|r| r.rtt_ms < u32::MAX && !r.endpoint.is_empty())
        .min_by_key(|r| r.rtt_ms)
}

/// Construye frame DERP dirigido sin broadcast: `NM2 | dst_pubkey(32B) | inner_frame`.
pub fn build_nm2_routed_frame(dst_pubkey: &[u8; 32], inner_frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 32 + inner_frame.len());
    out.extend_from_slice(b"NM2");
    out.extend_from_slice(dst_pubkey);
    out.extend_from_slice(inner_frame);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Lan,
    StunPublic,
    UpnpMapped,
}

#[derive(Debug, Clone)]
pub struct CandidateRoute {
    pub addr: SocketAddr,
    pub kind: RouteKind,
    pub rtt_ms: Option<u32>,
    pub last_pong: Option<Instant>,
}

#[derive(Debug)]
pub enum NodeEvent {
    Hello { vip: String, name: String, from: SocketAddr },
    Ack { vip: String, from: SocketAddr },
    DiscoPing { vip: String, tx_id: u64, from: SocketAddr },
    DiscoPong { vip: String, tx_id: u64, from: SocketAddr },
    Rekeyed { vip: String },
    Packet { sender_vip: String, packet: Vec<u8> },
}

/// Cliente userspace del túnel (magicsock): mide RTT entre rutas candidatas,
/// promueve DERP (NM2) <-> UDP directo en caliente y rota claves PFS automáticamente.
pub struct Node {
    pub local_vip: String,
    pub peer_vip: String,
    sock: UdpSocket,
    peer_addr: Option<SocketAddr>,
    candidates: Vec<CandidateRoute>,
    relay_tx: Option<Sender<Vec<u8>>>,
    relay_target_key: Option<[u8; 32]>,
    direct_ok: Arc<Mutex<bool>>,
    last_direct_rx: Arc<Mutex<Option<Instant>>>,
    pending_disco: Mutex<Option<(u64, Instant)>>,
    disco_probes_sent: HashMap<u64, (SocketAddr, Instant)>,
    disco_seq: u64,
    last_disco_tick: Instant,
    rekey_in_flight: bool,
    last_rekey_attempt: Option<Instant>,
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
            candidates: Vec::new(),
            relay_tx: None,
            relay_target_key: None,
            direct_ok: Arc::new(Mutex::new(false)),
            last_direct_rx: Arc::new(Mutex::new(None)),
            pending_disco: Mutex::new(None),
            disco_probes_sent: HashMap::new(),
            disco_seq: 1,
            last_disco_tick: Instant::now() - Duration::from_secs(10),
            rekey_in_flight: false,
            last_rekey_attempt: None,
            disco_rtt_ms: Arc::new(Mutex::new(None)),
        })
    }

    pub fn local_port(&self) -> Result<u16> {
        Ok(self.sock.local_addr()?.port())
    }

    pub fn set_peer(&mut self, addr: SocketAddr) {
        self.peer_addr = Some(addr);
        self.add_candidate(addr, RouteKind::StunPublic);
    }

    pub fn add_candidate(&mut self, addr: SocketAddr, kind: RouteKind) {
        if !self.candidates.iter().any(|c| c.addr == addr) {
            self.candidates.push(CandidateRoute {
                addr,
                kind,
                rtt_ms: None,
                last_pong: None,
            });
        }
    }

    pub fn candidates(&self) -> &[CandidateRoute] {
        &self.candidates
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Configura la clave pública Ed25519 destino (32 bytes) para encapsular el relay en `NM2`.
    pub fn set_relay_target_signing_key(&mut self, pub_raw: [u8; 32]) {
        self.relay_target_key = Some(pub_raw);
    }

    /// Activa el canal de relay. Devuelve un receiver de frames salientes para
    /// que el transporte WSS los envíe al backend DERP.
    pub fn enable_relay(&mut self) -> Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        self.relay_tx = Some(tx);
        rx
    }

    fn send_via_relay(&self, inner: &[u8]) -> Result<()> {
        let tx = self
            .relay_tx
            .as_ref()
            .ok_or_else(|| anyhow!("relay no activado"))?;
        let out = if let Some(dst) = self.relay_target_key {
            build_nm2_routed_frame(&dst, inner)
        } else {
            inner.to_vec()
        };
        tx.send(out)?;
        Ok(())
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

    /// Procesa un frame entrante desde el relay DERP (soporta paquetes `NM1` cifrados y `NM_REKEY_*`).
    pub fn feed_relay_event(&mut self, frame: &[u8]) -> Result<Option<NodeEvent>> {
        if frame.starts_with(b"NM_REKEY_") {
            return self.handle_control_packet(frame, None);
        }
        let (sender_vip, packet) = Self::parse_nm1_frame(frame)?;
        Ok(Some(NodeEvent::Packet { sender_vip, packet }))
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

    /// Sondea en paralelo todas las rutas candidatas (LAN, STUN, UPnP/NAT-PMP) para conmutar a la de menor RTT.
    pub fn probe_candidates(&mut self) -> usize {
        let mut addrs: Vec<SocketAddr> = self.candidates.iter().map(|c| c.addr).collect();
        if let Some(p) = self.peer_addr {
            if !addrs.contains(&p) {
                addrs.push(p);
            }
        }
        let now = Instant::now();
        self.disco_probes_sent.retain(|_, (_, ts)| now.duration_since(*ts) < Duration::from_secs(30));

        let mut sent = 0usize;
        for addr in addrs {
            let tx_id = self.disco_seq;
            self.disco_seq = self.disco_seq.wrapping_add(1).max(1);
            let msg = format!("NM_DISCO_PING|{tx_id}|{}", self.local_vip);
            if self.sock.send_to(msg.as_bytes(), addr).is_ok() {
                self.disco_probes_sent.insert(tx_id, (addr, Instant::now()));
                *self.pending_disco.lock().unwrap() = Some((tx_id, Instant::now()));
                sent += 1;
            }
        }
        self.last_disco_tick = Instant::now();
        sent
    }

    /// Inicia una rotación PFS efímera automática y la transmite al par (UDP directo o DERP).
    pub fn send_rekey_init(&mut self) -> Result<()> {
        let eph_pub = session::begin_pfs_rekey(&self.peer_vip)?;
        let msg = format!("NM_REKEY_INIT|{}|{}", self.local_vip, base64_encode(&eph_pub));
        self.rekey_in_flight = true;
        self.last_rekey_attempt = Some(Instant::now());
        if *self.direct_ok.lock().unwrap() {
            if let Some(addr) = self.peer_addr {
                if self.sock.send_to(msg.as_bytes(), addr).is_ok() {
                    return Ok(());
                }
            }
        }
        if self.relay_tx.is_some() {
            return self.send_via_relay(msg.as_bytes());
        }
        if let Some(addr) = self.peer_addr {
            self.sock.send_to(msg.as_bytes(), addr)?;
            return Ok(());
        }
        Err(anyhow!("sin transporte disponible para NM_REKEY_INIT"))
    }

    /// Mantenimiento periódico del loop de transporte:
    /// 1) Evalúa degradación DERP + sondeo Disco multi-ruta cada 5s.
    /// 2) Dispara rotación PFS automática al alcanzar 120s o límite de paquetes.
    pub fn tick(&mut self) {
        self.fallback_to_relay_if_stale(Duration::from_secs(15));
        if self.last_disco_tick.elapsed() >= Duration::from_secs(5) {
            let _ = self.probe_candidates();
        }
        if session::needs_rekey(&self.peer_vip) {
            let allow_retry = match self.last_rekey_attempt {
                Some(ts) => ts.elapsed() >= Duration::from_secs(10),
                None => true,
            };
            if !self.rekey_in_flight || allow_retry {
                let _ = self.send_rekey_init();
            }
        }
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

    fn select_best_candidate(&mut self, responder: SocketAddr, measured_rtt: u32) {
        if let Some(c) = self.candidates.iter_mut().find(|c| c.addr == responder) {
            c.rtt_ms = Some(measured_rtt);
            c.last_pong = Some(Instant::now());
        } else {
            self.candidates.push(CandidateRoute {
                addr: responder,
                kind: RouteKind::StunPublic,
                rtt_ms: Some(measured_rtt),
                last_pong: Some(Instant::now()),
            });
        }
        if let Some(best) = self
            .candidates
            .iter()
            .filter(|c| c.rtt_ms.is_some())
            .min_by_key(|c| c.rtt_ms.unwrap_or(u32::MAX))
        {
            self.peer_addr = Some(best.addr);
            *self.disco_rtt_ms.lock().unwrap() = best.rtt_ms;
        } else {
            self.peer_addr = Some(responder);
        }
    }

    fn handle_control_packet(
        &mut self,
        pkt: &[u8],
        from: Option<SocketAddr>,
    ) -> Result<Option<NodeEvent>> {
        let text = String::from_utf8_lossy(pkt);
        if pkt.starts_with(b"NM_HELLO|") {
            let mut parts = text.split('|');
            let _ = parts.next();
            let vip = parts.next().unwrap_or("").trim().to_string();
            let name = parts.next().unwrap_or("peer").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                if let Some(addr) = from {
                    self.peer_addr = Some(addr);
                    self.add_candidate(addr, RouteKind::StunPublic);
                    *self.direct_ok.lock().unwrap() = true;
                    *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                    let ack = format!("NM_ACK|{}|rust-cli|direct", self.local_vip);
                    let _ = self.sock.send_to(ack.as_bytes(), addr);
                    return Ok(Some(NodeEvent::Hello { vip, name, from: addr }));
                }
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_ACK|") {
            let mut parts = text.split('|');
            let _ = parts.next();
            let vip = parts.next().unwrap_or("").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                if let Some(addr) = from {
                    self.peer_addr = Some(addr);
                    self.add_candidate(addr, RouteKind::StunPublic);
                    *self.direct_ok.lock().unwrap() = true;
                    *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                    return Ok(Some(NodeEvent::Ack { vip, from: addr }));
                }
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_DISCO_PING|") {
            let mut parts = text.split('|');
            let _ = parts.next();
            let tx_id = parts.next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            let vip = parts.next().unwrap_or("").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                if let Some(addr) = from {
                    if self.peer_addr.is_none() {
                        self.peer_addr = Some(addr);
                    }
                    self.add_candidate(addr, RouteKind::StunPublic);
                    *self.direct_ok.lock().unwrap() = true;
                    *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                    let pong = format!("NM_DISCO_PONG|{tx_id}|{}", self.local_vip);
                    let _ = self.sock.send_to(pong.as_bytes(), addr);
                    return Ok(Some(NodeEvent::DiscoPing { vip, tx_id, from: addr }));
                }
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_DISCO_PONG|") {
            let mut parts = text.split('|');
            let _ = parts.next();
            let tx_id = parts.next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            let vip = parts.next().unwrap_or("").trim().to_string();
            if vip.starts_with("10.0.0.") && vip != self.local_vip {
                if let Some(addr) = from {
                    *self.direct_ok.lock().unwrap() = true;
                    *self.last_direct_rx.lock().unwrap() = Some(Instant::now());
                    let rtt = if let Some((_, started)) = self.disco_probes_sent.remove(&tx_id) {
                        started.elapsed().as_millis().min(u32::MAX as u128) as u32
                    } else if let Some((pending_id, started)) = *self.pending_disco.lock().unwrap() {
                        if pending_id == tx_id {
                            started.elapsed().as_millis().min(u32::MAX as u128) as u32
                        } else {
                            50
                        }
                    } else {
                        50
                    };
                    self.select_best_candidate(addr, rtt);
                    return Ok(Some(NodeEvent::DiscoPong { vip, tx_id, from: addr }));
                }
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_REKEY_INIT|") {
            let mut parts = text.split('|');
            let _ = parts.next();
            let vip = parts.next().unwrap_or("").trim().to_string();
            let b64 = parts.next().unwrap_or("").trim();
            if let Ok(raw) = base64_decode(b64) {
                if raw.len() == 32 && vip == self.peer_vip {
                    let mut peer_eph = [0u8; 32];
                    peer_eph.copy_from_slice(&raw);
                    let our_eph = session::begin_pfs_rekey(&self.peer_vip)?;
                    let ack = format!("NM_REKEY_ACK|{}|{}", self.local_vip, base64_encode(&our_eph));
                    if let Some(addr) = from.or(self.peer_addr) {
                        let _ = self.sock.send_to(ack.as_bytes(), addr);
                    } else if self.relay_tx.is_some() {
                        let _ = self.send_via_relay(ack.as_bytes());
                    }
                    session::finish_pfs_rekey(&self.peer_vip, &peer_eph)?;
                    self.rekey_in_flight = false;
                    return Ok(Some(NodeEvent::Rekeyed { vip }));
                }
            }
            return Ok(None);
        }

        if pkt.starts_with(b"NM_REKEY_ACK|") {
            let mut parts = text.split('|');
            let _ = parts.next();
            let vip = parts.next().unwrap_or("").trim().to_string();
            let b64 = parts.next().unwrap_or("").trim();
            if let Ok(raw) = base64_decode(b64) {
                if raw.len() == 32 && vip == self.peer_vip && self.rekey_in_flight {
                    let mut peer_eph = [0u8; 32];
                    peer_eph.copy_from_slice(&raw);
                    session::finish_pfs_rekey(&self.peer_vip, &peer_eph)?;
                    self.rekey_in_flight = false;
                    return Ok(Some(NodeEvent::Rekeyed { vip }));
                }
            }
            return Ok(None);
        }

        Ok(None)
    }

    /// Lee un datagrama UDP (con timeout de 50ms) y procesa `NM_HELLO`, `NM_ACK`, `NM_DISCO_*`, `NM_REKEY_*` o `NM1`.
    pub fn poll_udp_once(&mut self) -> Result<Option<NodeEvent>> {
        let mut buf = [0u8; 4200];
        let (len, from) = loop {
            match self.sock.recv_from(&mut buf) {
                Ok(res) => break res,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                // En Windows (WSAECONNRESET 10054), sondar un candidato UDP muerto devuelve ConnectionReset en recv_from.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        };

        let pkt = &buf[..len];
        if pkt.starts_with(b"NM_") {
            return self.handle_control_packet(pkt, Some(from));
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
    /// (si el enlace directo está confirmado o configurado); si no, usa el relay NM2.
    pub fn send_packet(&self, ip_packet: &[u8]) -> Result<()> {
        let frame = self.build_nm1_frame(ip_packet)?;

        if *self.direct_ok.lock().unwrap() {
            if let Some(addr) = self.peer_addr {
                if self.sock.send_to(&frame, addr).is_ok() {
                    return Ok(());
                }
            }
        } else if self.relay_tx.is_none() {
            if let Some(addr) = self.peer_addr {
                if self.sock.send_to(&frame, addr).is_ok() {
                    *self.direct_ok.lock().unwrap() = true;
                    return Ok(());
                }
            }
        }

        if self.relay_tx.is_some() {
            return self.send_via_relay(&frame);
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
    reply[12..16].copy_from_slice(&req[16..20]);
    reply[16..20].copy_from_slice(&req[12..16]);
    reply[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = inet_checksum(&reply[0..ihl]);
    reply[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    reply[ihl] = 0; // Echo Reply
    reply[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let icmp_csum = inet_checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(reply)
}
