//! NAT Traversal avanzado:
//! - Evasión de NAT simétrico (Birthday Paradox: múltiples sockets efímeros UDP)
//! - Paquete RFC 6886 NAT-PMP para mapeo automático en router
//! - Paquete SSDP M-SEARCH para descubrimiento UPnP IGD

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Abre hasta `count` sockets UDP efímeros simultáneos para sondeo Birthday Paradox
/// frente a NATs simétricos.
pub fn bind_birthday_sockets(count: usize) -> Vec<UdpSocket> {
    let mut sockets = Vec::with_capacity(count);
    for _ in 0..count {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(80)));
            sockets.push(sock);
        }
    }
    sockets
}

/// Envía una ráfaga de sondas Disco/STUN desde múltiples sockets efímeros hacia un rango
/// de puertos del par para forzar colisión de puertos en NAT simétrico.
pub fn spray_birthday_probes(
    sockets: &[UdpSocket],
    peer_ip: Ipv4Addr,
    base_port: u16,
    port_spread: u16,
    probe_payload: &[u8],
) -> usize {
    let mut sent = 0usize;
    let spread = port_spread.max(1);
    for (idx, sock) in sockets.iter().enumerate() {
        let port = base_port.saturating_add((idx as u16) % spread);
        if port == 0 {
            continue;
        }
        let target = SocketAddr::from((peer_ip, port));
        if sock.send_to(probe_payload, target).is_ok() {
            sent += 1;
        }
    }
    sent
}

/// Construye una petición NAT-PMP (RFC 6886) para mapear puerto UDP (opcode=1).
pub fn nat_pmp_udp_map_request(internal_port: u16, suggested_ext_port: u16, lifetime_sec: u32) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = 0; // Version 0
    buf[1] = 1; // Opcode 1 = Map UDP
    // buf[2..4] reserved = 0
    buf[4..6].copy_from_slice(&internal_port.to_be_bytes());
    buf[6..8].copy_from_slice(&suggested_ext_port.to_be_bytes());
    buf[8..12].copy_from_slice(&lifetime_sec.to_be_bytes());
    buf
}

/// Parsea una respuesta NAT-PMP (RFC 6886) devolviendo `(internal_port, external_port, lifetime)`.
pub fn parse_nat_pmp_map_response(resp: &[u8]) -> Option<(u16, u16, u32)> {
    if resp.len() < 16 || resp[0] != 0 || (resp[1] & 0x7F) != 1 {
        return None;
    }
    let result_code = u16::from_be_bytes([resp[2], resp[3]]);
    if result_code != 0 {
        return None;
    }
    let internal = u16::from_be_bytes([resp[8], resp[9]]);
    let external = u16::from_be_bytes([resp[10], resp[11]]);
    let lifetime = u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]);
    Some((internal, external, lifetime))
}

/// Petición SSDP M-SEARCH para descubrir routers UPnP IGD en 239.255.255.250:1900.
pub fn upnp_ssdp_discover_packet() -> &'static [u8] {
    b"M-SEARCH * HTTP/1.1\r\n\
      HOST: 239.255.255.250:1900\r\n\
      MAN: \"ssdp:discover\"\r\n\
      MX: 2\r\n\
      ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
}
